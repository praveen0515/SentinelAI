"""
SentinelAI Database Management Module
Handles asynchronous MongoDB operations, indexing, and aggregations.
Includes an in-memory buffer fallback when MongoDB is temporarily unreachable.
"""

import logging
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from backend.config import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages MongoDB connections and SIEM data persistence."""

    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.is_connected: bool = False
        # In-memory fallback stores for offline/standalone execution
        self._memory_logs: List[Dict[str, Any]] = []
        self._memory_alerts: List[Dict[str, Any]] = []
        self._max_memory_items: int = 5000

    async def connect(self):
        """Establish asynchronous MongoDB connection and create indexes."""
        try:
            self.client = AsyncIOMotorClient(
                settings.MONGODB_URI,
                serverSelectionTimeoutMS=2500,
                connectTimeoutMS=2500
            )
            # Ping database to confirm connectivity
            await self.client.admin.command('ping')
            self.db = self.client[settings.MONGODB_DB_NAME]
            self.is_connected = True
            logger.info("Connected successfully to MongoDB at %s", settings.MONGODB_URI)
            await self.create_indexes()
        except Exception as exc:
            self.is_connected = False
            logger.warning("MongoDB unavailable (%s). Operating in memory buffer mode.", exc)

    async def close(self):
        """Close database connection."""
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB connection closed.")

    async def create_indexes(self):
        """Create optimized indexes for fast SIEM log searching and aggregation."""
        if not self.is_connected or self.db is None:
            return

        try:
            logs = self.db.logs
            await logs.create_index([("timestamp", -1)])
            await logs.create_index([("client_ip", 1), ("timestamp", -1)])
            await logs.create_index([("is_threat", 1), ("timestamp", -1)])
            await logs.create_index([("severity", 1)])
            await logs.create_index([("threat_category", 1)])

            alerts = self.db.threat_alerts
            await alerts.create_index([("timestamp", -1)])
            await alerts.create_index([("severity", 1)])
            await alerts.create_index([("acknowledged", 1)])
            await alerts.create_index([("client_ip", 1)])
            logger.info("Database indexes successfully ensured.")
        except Exception as exc:
            logger.error("Failed creating MongoDB indexes: %s", exc)

    async def insert_log(self, log_entry: Dict[str, Any]) -> str:
        """Store single processed log."""
        if "timestamp" not in log_entry or not isinstance(log_entry["timestamp"], datetime):
            log_entry["timestamp"] = datetime.now(timezone.utc)

        if self.is_connected and self.db is not None:
            res = await self.db.logs.insert_one(log_entry)
            return str(res.inserted_id)
        else:
            if len(self._memory_logs) >= self._max_memory_items:
                self._memory_logs.pop(0)
            log_id = f"mem_log_{len(self._memory_logs) + 1}"
            entry = dict(log_entry)
            entry["_id"] = log_id
            self._memory_logs.append(entry)
            return log_id

    async def insert_logs_batch(self, log_entries: List[Dict[str, Any]]) -> int:
        """Store multiple logs in bulk."""
        if not log_entries:
            return 0

        for entry in log_entries:
            if "timestamp" not in entry or not isinstance(entry["timestamp"], datetime):
                entry["timestamp"] = datetime.now(timezone.utc)

        if self.is_connected and self.db is not None:
            res = await self.db.logs.insert_many(log_entries)
            return len(res.inserted_ids)
        else:
            for entry in log_entries:
                await self.insert_log(entry)
            return len(log_entries)

    async def insert_alert(self, alert_entry: Dict[str, Any]) -> str:
        """Store threat alert."""
        if "timestamp" not in alert_entry or not isinstance(alert_entry["timestamp"], datetime):
            alert_entry["timestamp"] = datetime.now(timezone.utc)
        if "acknowledged" not in alert_entry:
            alert_entry["acknowledged"] = False

        if self.is_connected and self.db is not None:
            res = await self.db.threat_alerts.insert_one(alert_entry)
            return str(res.inserted_id)
        else:
            if len(self._memory_alerts) >= self._max_memory_items:
                self._memory_alerts.pop(0)
            alert_id = f"mem_alert_{len(self._memory_alerts) + 1}"
            entry = dict(alert_entry)
            entry["_id"] = alert_id
            self._memory_alerts.append(entry)
            return alert_id

    async def get_recent_logs(
        self,
        limit: int = 100,
        skip: int = 0,
        threat_only: bool = False,
        min_severity: Optional[str] = None,
        ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent logs matching filtering criteria."""
        query: Dict[str, Any] = {}
        if threat_only:
            query["is_threat"] = True
        if ip:
            query["client_ip"] = ip
        if min_severity:
            severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_severity in severities:
                valid_sevs = severities[severities.index(min_severity):]
                query["severity"] = {"$in": valid_sevs}

        if self.is_connected and self.db is not None:
            cursor = self.db.logs.find(query).sort("timestamp", -1).skip(skip).limit(limit)
            items = []
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id"))
                items.append(doc)
            return items
        else:
            results = []
            for item in reversed(self._memory_logs):
                if threat_only and not item.get("is_threat"):
                    continue
                if ip and item.get("client_ip") != ip:
                    continue
                if min_severity and item.get("severity") != min_severity:
                    continue
                doc = dict(item)
                doc["id"] = str(doc.get("_id"))
                results.append(doc)
            return results[skip : skip + limit]

    async def get_recent_alerts(
        self,
        limit: int = 50,
        acknowledged: Optional[bool] = None,
        min_severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch threat alerts."""
        query: Dict[str, Any] = {}
        if acknowledged is not None:
            query["acknowledged"] = acknowledged
        if min_severity:
            severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_severity in severities:
                valid_sevs = severities[severities.index(min_severity):]
                query["severity"] = {"$in": valid_sevs}

        if self.is_connected and self.db is not None:
            cursor = self.db.threat_alerts.find(query).sort("timestamp", -1).limit(limit)
            items = []
            async for doc in cursor:
                doc["id"] = str(doc.pop("_id"))
                items.append(doc)
            return items
        else:
            results = []
            for item in reversed(self._memory_alerts):
                if acknowledged is not None and item.get("acknowledged") != acknowledged:
                    continue
                if min_severity and item.get("severity") != min_severity:
                    continue
                doc = dict(item)
                doc["id"] = str(doc.get("_id"))
                results.append(doc)
            return results[:limit]

    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "analyst") -> bool:
        """Mark an alert as reviewed/acknowledged."""
        now = datetime.now(timezone.utc)
        if self.is_connected and self.db is not None:
            from bson import ObjectId
            try:
                res = await self.db.threat_alerts.update_one(
                    {"_id": ObjectId(alert_id)},
                    {"$set": {"acknowledged": True, "acknowledged_by": acknowledged_by, "acknowledged_at": now}}
                )
                return res.modified_count > 0
            except Exception:
                res = await self.db.threat_alerts.update_one(
                    {"_id": alert_id},
                    {"$set": {"acknowledged": True, "acknowledged_by": acknowledged_by, "acknowledged_at": now}}
                )
                return res.modified_count > 0
        else:
            for alert in self._memory_alerts:
                if str(alert.get("_id")) == alert_id or alert.get("id") == alert_id:
                    alert["acknowledged"] = True
                    alert["acknowledged_by"] = acknowledged_by
                    alert["acknowledged_at"] = now
                    return True
            return False

    async def get_threat_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """Aggregate high-level threat metrics."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        if self.is_connected and self.db is not None:
            total_logs = await self.db.logs.count_documents({"timestamp": {"$gte": cutoff}})
            threat_logs = await self.db.logs.count_documents({"timestamp": {"$gte": cutoff}, "is_threat": True})
            unacked_alerts = await self.db.threat_alerts.count_documents({"acknowledged": False})
            critical_threats = await self.db.logs.count_documents({
                "timestamp": {"$gte": cutoff},
                "severity": {"$in": ["HIGH", "CRITICAL"]}
            })
        else:
            window_logs = [l for l in self._memory_logs if l.get("timestamp", datetime.min.replace(tzinfo=timezone.utc)) >= cutoff]
            total_logs = len(window_logs)
            threat_logs = sum(1 for l in window_logs if l.get("is_threat"))
            unacked_alerts = sum(1 for a in self._memory_alerts if not a.get("acknowledged"))
            critical_threats = sum(1 for l in window_logs if l.get("severity") in ["HIGH", "CRITICAL"])

        anomaly_rate = (threat_logs / total_logs * 100.0) if total_logs > 0 else 0.0

        return {
            "time_window_hours": hours,
            "total_logs": total_logs,
            "threats_detected": threat_logs,
            "anomaly_rate_percent": round(anomaly_rate, 2),
            "critical_high_count": critical_threats,
            "unacknowledged_alerts": unacked_alerts,
            "system_status": "NORMAL" if anomaly_rate < 10 else ("ELEVATED" if anomaly_rate < 25 else "CRITICAL")
        }

    async def get_top_threat_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the source IPs generating the most anomalies."""
        if self.is_connected and self.db is not None:
            pipeline = [
                {"$match": {"is_threat": True}},
                {"$group": {
                    "_id": "$client_ip",
                    "count": {"$sum": 1},
                    "country": {"$last": "$country"},
                    "max_severity": {"$max": "$severity"},
                    "last_seen": {"$max": "$timestamp"}
                }},
                {"$sort": {"count": -1}},
                {"$limit": limit}
            ]
            results = []
            async for doc in self.db.logs.aggregate(pipeline):
                results.append({
                    "ip": doc["_id"],
                    "threat_count": doc["count"],
                    "country": doc.get("country", "Unknown"),
                    "max_severity": doc.get("max_severity", "LOW"),
                    "last_seen": doc.get("last_seen")
                })
            return results
        else:
            ip_counts: Dict[str, Dict[str, Any]] = {}
            for l in self._memory_logs:
                if l.get("is_threat"):
                    ip = l.get("client_ip", "unknown")
                    if ip not in ip_counts:
                        ip_counts[ip] = {
                            "ip": ip,
                            "threat_count": 0,
                            "country": l.get("country", "Unknown"),
                            "max_severity": l.get("severity", "LOW"),
                            "last_seen": l.get("timestamp")
                        }
                    ip_counts[ip]["threat_count"] += 1
            sorted_ips = sorted(ip_counts.values(), key=lambda x: x["threat_count"], reverse=True)
            return sorted_ips[:limit]

    async def get_severity_distribution(self) -> Dict[str, int]:
        """Aggregate log counts by severity level."""
        distribution = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        if self.is_connected and self.db is not None:
            pipeline = [
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
            ]
            async for doc in self.db.logs.aggregate(pipeline):
                sev = doc["_id"]
                if sev in distribution:
                    distribution[sev] = doc["count"]
        else:
            for log in self._memory_logs:
                sev = log.get("severity", "INFO")
                if sev in distribution:
                    distribution[sev] += 1

        return distribution

    async def get_attack_category_breakdown(self) -> List[Dict[str, Any]]:
        """Categorical breakdown of detected threat attack types."""
        if self.is_connected and self.db is not None:
            pipeline = [
                {"$match": {"is_threat": True}},
                {"$group": {"_id": "$threat_category", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            breakdown = []
            async for doc in self.db.logs.aggregate(pipeline):
                category = doc["_id"] or "Unclassified Anomaly"
                breakdown.append({"category": category, "count": doc["count"]})
            return breakdown
        else:
            cat_counts: Dict[str, int] = {}
            for l in self._memory_logs:
                if l.get("is_threat"):
                    cat = l.get("threat_category", "Unclassified Anomaly") or "Unclassified Anomaly"
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
            return [{"category": k, "count": v} for k, v in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)]

    async def get_hourly_threat_trend(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Hourly timeline buckets for threats vs normal logs."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        if self.is_connected and self.db is not None:
            pipeline = [
                {"$match": {"timestamp": {"$gte": cutoff}}},
                {"$project": {
                    "hour": {
                        "$dateToString": {
                            "format": "%Y-%m-%d %H:00",
                            "date": "$timestamp"
                        }
                    },
                    "is_threat": "$is_threat",
                    "severity": "$severity"
                }},
                {"$group": {
                    "_id": "$hour",
                    "total": {"$sum": 1},
                    "threats": {"$sum": {"$cond": ["$is_threat", 1, 0]}},
                    "critical": {"$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}},
                    "high": {"$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}},
                    "medium": {"$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}},
                    "low": {"$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}}
                }},
                {"$sort": {"_id": 1}}
            ]
            trend = []
            async for doc in self.db.logs.aggregate(pipeline):
                trend.append({
                    "timestamp": doc["_id"],
                    "total_requests": doc["total"],
                    "threat_count": doc["threats"],
                    "critical": doc["critical"],
                    "high": doc["high"],
                    "medium": doc["medium"],
                    "low": doc["low"]
                })
            return trend
        else:
            # Fallback memory bucket grouping
            buckets: Dict[str, Dict[str, int]] = {}
            for l in self._memory_logs:
                ts = l.get("timestamp")
                if isinstance(ts, datetime) and ts >= cutoff:
                    hour_key = ts.strftime("%Y-%m-%d %H:00")
                    if hour_key not in buckets:
                        buckets[hour_key] = {"total_requests": 0, "threat_count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
                    buckets[hour_key]["total_requests"] += 1
                    if l.get("is_threat"):
                        buckets[hour_key]["threat_count"] += 1
                        sev = l.get("severity", "").lower()
                        if sev in buckets[hour_key]:
                            buckets[hour_key][sev] += 1
            trend = [{"timestamp": k, **v} for k, v in sorted(buckets.items())]
            return trend

    async def get_geo_threat_map_data(self) -> List[Dict[str, Any]]:
        """Return geographic location data for threats to power the live map."""
        if self.is_connected and self.db is not None:
            pipeline = [
                {"$match": {"is_threat": True, "latitude": {"$exists": True, "$ne": None}}},
                {"$group": {
                    "_id": {
                        "country": "$country",
                        "city": "$city",
                        "lat": "$latitude",
                        "lon": "$longitude"
                    },
                    "threat_count": {"$sum": 1},
                    "top_category": {"$first": "$threat_category"},
                    "max_severity": {"$max": "$severity"}
                }},
                {"$sort": {"threat_count": -1}},
                {"$limit": 100}
            ]
            geo_points = []
            async for doc in self.db.logs.aggregate(pipeline):
                geo_points.append({
                    "country": doc["_id"]["country"],
                    "city": doc["_id"]["city"],
                    "latitude": doc["_id"]["lat"],
                    "longitude": doc["_id"]["lon"],
                    "threat_count": doc["threat_count"],
                    "top_category": doc.get("top_category", "Anomaly"),
                    "max_severity": doc.get("max_severity", "MEDIUM")
                })
            return geo_points
        else:
            geo_map: Dict[str, Dict[str, Any]] = {}
            for l in self._memory_logs:
                if l.get("is_threat") and l.get("latitude") is not None:
                    key = f"{l.get('latitude')}_{l.get('longitude')}"
                    if key not in geo_map:
                        geo_map[key] = {
                            "country": l.get("country", "Unknown"),
                            "city": l.get("city", "Unknown"),
                            "latitude": l.get("latitude"),
                            "longitude": l.get("longitude"),
                            "threat_count": 0,
                            "top_category": l.get("threat_category", "Anomaly"),
                            "max_severity": l.get("severity", "MEDIUM")
                        }
                    geo_map[key]["threat_count"] += 1
            return list(geo_map.values())


# Singleton instance
db_manager = DatabaseManager()
