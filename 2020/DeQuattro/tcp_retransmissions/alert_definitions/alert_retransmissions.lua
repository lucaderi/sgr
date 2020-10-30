--
-- (C) 2019-20 - ntop.org
--

-- #######################################################

-- @brief Prepare an alert table used to generate the alert
-- @param alert_severity A severity as defined in `alert_consts.alert_severities`
-- @param info A flow info table created during the script who has the percentage of retransmissions.
-- @return A table with the alert built
local function createRetransmissions(alert_severity, retransmissions_info)

   local built = {
      alert_serverity = alert_severity,
      alert_type_params = retransmissions_info,
   }

   return built
end

-- ########################################

local alert_keys = require "alert_keys"

return {
   alert_key = alert_keys.ntopng.alert_too_many_retransmissions,
   i18n_title = "Retransmissions alert",
   icon = "fas fa-exclamation",
   creator = createRetransmissions,
}
