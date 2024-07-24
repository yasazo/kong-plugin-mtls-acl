-- Import required modules
local clear_header = kong.service.request.clear_header

-- Utility functions
local function is_empty(s)
    return s == nil or s == ''
end

local function contains (tab, val)
    for _, value in ipairs(tab) do
        if value == val then
            return true
        end
    end
    return false
end

local function get_header_value(header_name)
    local headers = ngx.req.get_headers()
    for k, v in pairs(headers) do
        if string.lower(k) == string.lower(header_name) then
            return v
        end
    end
    return nil
end

-- Define the handler
local MtlsAcl = {
    MtlsAcl.VERSION = "1.0.0"
    MtlsAcl.PRIORITY = 950
}

-- Define the access phase
function MtlsAcl:access(config)
    local certificate = get_header_value(config.certificate_header_name)
    if not is_empty(certificate) then
        if not is_empty(config.allow) then
            if contains(config.allow, certificate) then
                if config.hide_certificate_header then
                    clear_header(config.certificate_header_name)
                end
                return
            end
        end
        if not is_empty(config.deny) then
            if not contains(config.deny, certificate) then
                if config.hide_certificate_header then
                    clear_header(config.certificate_header_name)
                end
                return
            end
        end
    end

    -- Return an error response if the certificate is not allowed or denied
    return kong.response.exit(403, {
        message = "You cannot consume this service"
    })
end

return MtlsAcl