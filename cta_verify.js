function verifyCTA(cta) {
  if (!cta.work_hash || !cta.timestamp_utc || !cta.creator_id) {
    return false;
  }
  return true;
}
