--
-- (C) 2019-20 - ntop.org
--

local user_scripts = require("user_scripts")
local flow_consts = require("flow_consts")

-- #################################################################

local script = {
   -- Script category
   category = user_scripts.script_categories.security, 

   -- Priority
   prio = -20, -- Lower priority (executed after) than default 0 priority

   -- NOTE: hooks defined below
   hooks = {},

   -- use this plugin only with this protocol
   l7_proto_id = 3, -- 3 == SMTP

   -- Specify the default value whe clicking on the "Reset Default" button
   default_value = {
      items = {},
   },

   gui = {
      i18n_title        = "unexpected_smtp.unexpected_smtp_title",
      i18n_description  = "unexpected_smtp.unexpected_smtp_description",

      input_builder     = "items_list",
      item_list_type    = "string",
      input_title       = i18n("unexpected_smtp.title"),
      input_description = i18n("unexpected_smtp.description"),
   }
}

-- #################################################################

function script.hooks.protocolDetected(now, conf)
   if(table.len(conf.items) > 0) then
      local ok = 0
      local flow_info = flow.getInfo()
      local server_ip = flow_info["srv.ip"]
      
      for _, smtp_ip in pairs(conf.items) do
         if server_ip == smtp_ip then
            ok = 1
            break
         end
      end

      if ok == 0 then
         flow.triggerStatus(
            flow_consts.status_types.status_unexpected_smtp.create(
               flow_consts.status_types.status_unexpected_smtp.alert_severity,
               server_ip
            ),
            100, -- flow_score
            0, -- cli_score
            100 --srv_score
         )
      end
   end
end

-- #################################################################

return script
