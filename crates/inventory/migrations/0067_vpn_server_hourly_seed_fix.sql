-- Correct only midnight buckets that are still the untouched 0043 seed: the
-- seed's last_sample_ts is the 23:59:59.999 marker, which any real tick replaces.
CREATE TEMP TABLE vpn_hourly_seed_corrections AS
WITH daily AS (
    SELECT server_id, date, SUM(upload_bytes) AS upload_bytes,
           SUM(download_bytes) AS download_bytes
    FROM vpn_user_daily
    GROUP BY server_id, date
), candidates AS (
    SELECT midnight.server_id, midnight.hour,
           midnight.upload_bytes AS old_upload,
           midnight.download_bytes AS old_download,
           MAX(0, daily.upload_bytes - SUM(other.upload_bytes)) AS upload_bytes,
           MAX(0, daily.download_bytes - SUM(other.download_bytes)) AS download_bytes
    FROM daily
    JOIN vpn_server_hourly midnight
      ON midnight.server_id = daily.server_id
     AND midnight.hour = daily.date || 'T00:00:00.000Z'
     AND midnight.upload_bytes = daily.upload_bytes
     AND midnight.download_bytes = daily.download_bytes
     AND midnight.last_sample_ts = daily.date || 'T23:59:59.999Z'
    JOIN vpn_server_hourly other
      ON other.server_id = daily.server_id
     AND other.hour > midnight.hour
     AND other.hour < date(daily.date, '+1 day') || 'T00:00:00.000Z'
    GROUP BY midnight.server_id, midnight.hour
)
SELECT * FROM candidates
WHERE upload_bytes != old_upload OR download_bytes != old_download;

CREATE UNIQUE INDEX temp.vpn_hourly_seed_corrections_key
    ON vpn_hourly_seed_corrections (server_id, hour);

INSERT INTO audit_log (actor, action, target, payload)
SELECT 'system', 'migration.vpn_server_hourly.seed_fix', server_id,
       json_object('hour', hour, 'old_upload', old_upload, 'old_download', old_download,
                   'upload_bytes', upload_bytes, 'download_bytes', download_bytes)
FROM vpn_hourly_seed_corrections;

UPDATE vpn_server_hourly
SET (upload_bytes, download_bytes) = (
    SELECT c.upload_bytes, c.download_bytes FROM vpn_hourly_seed_corrections c
    WHERE c.server_id = vpn_server_hourly.server_id AND c.hour = vpn_server_hourly.hour
)
WHERE EXISTS (
    SELECT 1 FROM vpn_hourly_seed_corrections c
    WHERE c.server_id = vpn_server_hourly.server_id AND c.hour = vpn_server_hourly.hour
);

DROP TABLE vpn_hourly_seed_corrections;
