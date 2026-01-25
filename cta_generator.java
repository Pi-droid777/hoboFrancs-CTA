public class CTAGenerator {

    public static JSONObject generateCTA(byte[] workBytes) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(workBytes);

        String workHash = Base64.encodeToString(hash, Base64.NO_WRAP);
        String timestamp = Instant.now().toString();
        String creatorId = UUID.randomUUID().toString();

        JSONObject cta = new JSONObject();
        cta.put("system", "HoboFrancs CTA");
        cta.put("creator_id", creatorId);
        cta.put("timestamp_utc", timestamp);
        cta.put("work_hash", workHash);
        cta.put("status", "LOCAL_VERIFIED");

        return cta;
    }
}
