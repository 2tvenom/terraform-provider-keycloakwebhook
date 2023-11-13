resource "keycloakwebhook_webhook" "default" {
  realm = "master"
  items = [
    {
      enabled = true
      url     = "https://pipedream.m.pipedream.net"
      secret  = "A3jt6D8lz"
      event_types = [
        "access.REMOVE_TOTP",
        "access.UPDATE_TOTP",
        "access.LOGIN",
        "access.LOGOUT",
        "access.REGISTER",
        "access.UPDATE_PASSWORD",
        "access.VERIFY_EMAIL",
        "access.SEND_VERIFY_EMAIL",
        "access.RESET_PASSWORD"
      ]
    }
  ]
}