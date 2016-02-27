package gitbucket.core.controller

import gitbucket.core.admin.html
import gitbucket.core.service.{AccountService, SystemSettingsService}
import gitbucket.core.util.AdminAuthenticator
import gitbucket.core.ssh.SshServer
import gitbucket.core.plugin.PluginRegistry
import SystemSettingsService._
import io.github.gitbucket.scalatra.forms._

class SystemSettingsController extends SystemSettingsControllerBase
  with AccountService with AdminAuthenticator

trait SystemSettingsControllerBase extends ControllerBase {
  self: AccountService with AdminAuthenticator =>

  private val form = mapping(
    "baseUrl"                  -> trim(label("Base URL", optional(text()))),
    "information"              -> trim(label("Information", optional(text()))),
    "allowAccountRegistration" -> trim(label("Account registration", boolean())),
    "allowAnonymousAccess"     -> trim(label("Anonymous access", boolean())),
    "isCreateRepoOptionPublic" -> trim(label("Default option to create a new repository", boolean())),
    "gravatar"                 -> trim(label("Gravatar", boolean())),
    "notification"             -> trim(label("Notification", boolean())),
    "activityLogLimit"         -> trim(label("Limit of activity logs", optional(number()))),
    "ssh"                      -> trim(label("SSH access", boolean())),
    "sshHost"                  -> trim(label("SSH host", optional(text()))),
    "sshPort"                  -> trim(label("SSH port", optional(number()))),
    "sshGenericUser"           -> trim(label("SSH generic user", boolean())),
    "useSMTP"                  -> trim(label("SMTP", boolean())),
    "smtp"                     -> optionalIfNotChecked("useSMTP", mapping(
        "host"                     -> trim(label("SMTP Host", text(required))),
        "port"                     -> trim(label("SMTP Port", optional(number()))),
        "user"                     -> trim(label("SMTP User", optional(text()))),
        "password"                 -> trim(label("SMTP Password", optional(text()))),
        "ssl"                      -> trim(label("Enable SSL", optional(boolean()))),
        "fromAddress"              -> trim(label("FROM Address", optional(text()))),
        "fromName"                 -> trim(label("FROM Name", optional(text())))
    )(Smtp.apply)),
    "ldapAuthentication"       -> trim(label("LDAP", boolean())),
    "ldap"                     -> optionalIfNotChecked("ldapAuthentication", mapping(
        "host"                     -> trim(label("LDAP host", text(required))),
        "port"                     -> trim(label("LDAP port", optional(number()))),
        "bindDN"                   -> trim(label("Bind DN", optional(text()))),
        "bindPassword"             -> trim(label("Bind Password", optional(text()))),
        "baseDN"                   -> trim(label("Base DN", text(required))),
        "userNameAttribute"        -> trim(label("User name attribute", text(required))),
        "additionalFilterCondition"-> trim(label("Additional filter condition", optional(text()))),
        "fullNameAttribute"        -> trim(label("Full name attribute", optional(text()))),
        "mailAttribute"            -> trim(label("Mail address attribute", optional(text()))),
        "tls"                      -> trim(label("Enable TLS", optional(boolean()))),
        "ssl"                      -> trim(label("Enable SSL", optional(boolean()))),
        "keystore"                 -> trim(label("Keystore", optional(text())))
    )(Ldap.apply))
  )(SystemSettings.apply).verifying { settings =>
    Vector(
      if(settings.ssh && settings.baseUrl.isEmpty){
        Some("baseUrl" -> "Base URL is required if SSH access is enabled.")
      } else None,
      if(settings.ssh && settings.sshHost.isEmpty){
        Some("sshHost" -> "SSH host is required if SSH access is enabled.")
      } else None
    ).flatten
  }

  private val pluginForm = mapping(
    "pluginId" -> list(trim(label("", text())))
  )(PluginForm.apply)

  case class PluginForm(pluginIds: List[String])

  get("/admin/system")(adminOnly {
    html.system(flash.get("info"))
  })

  post("/admin/system", form)(adminOnly { form =>
    saveSystemSettings(form)

    if (form.sshAddress != context.settings.sshAddress) {
      SshServer.stop()
       for {
         sshAddress <- form.sshAddress
         baseUrl    <- form.baseUrl
       }
       SshServer.start(sshAddress, baseUrl)
    }

    flash += "info" -> "System settings has been updated."
    redirect("/admin/system")
  })

  get("/admin/plugins")(adminOnly {
    html.plugins(PluginRegistry().getPlugins())
  })

}
