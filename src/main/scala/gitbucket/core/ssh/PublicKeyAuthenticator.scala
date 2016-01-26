package gitbucket.core.ssh

import java.security.PublicKey

import gitbucket.core.model.SshKey
import gitbucket.core.service.SshKeyService
import gitbucket.core.servlet.Database
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.session.ServerSession
import org.apache.sshd.common.session.Session

object PublicKeyAuthenticator {
  // put in the ServerSession here to be read by GitCommand later
  private val userNameSessionKey = new Session.AttributeKey[String]

  def putUserName(serverSession:ServerSession, userName:String):Unit =
    serverSession.setAttribute(userNameSessionKey, userName)

  def getUserName(serverSession:ServerSession):Option[String] =
    Option(serverSession.getAttribute(userNameSessionKey))
}

class PublicKeyAuthenticator(genericUser:Option[String]) extends PublickeyAuthenticator with SshKeyService {
  override def authenticate(username: String, key: PublicKey, session: ServerSession): Boolean =
    genericUser match {
      case Some(generic) => authenticateGenericUser(username, key, session, generic)
      case None          => authenticateLoginUser(username, key, session)
    }

  private def authenticateLoginUser(username: String, key: PublicKey, session: ServerSession): Boolean = {
    val authenticated =
      Database()
      .withSession { implicit dbSession => getPublicKeys(username) }
      .map(_.publicKey)
      .flatMap(SshUtil.str2PublicKey)
      .contains(key)
    if (authenticated) {
      PublicKeyAuthenticator.putUserName(session, username)
    }
    authenticated
  }

  private def authenticateGenericUser(username: String, key: PublicKey, session: ServerSession, genericUser:String): Boolean =
    if (username == genericUser) {
      // find all users having the key we got from ssh
      val possibleUserNames =
        Database()
        .withSession { implicit dbSession => getAllKeys() }
        .filter { sshKey =>
           Option(sshKey.publicKey)
		  .filter(_.trim.nonEmpty)
		  .flatMap(SshUtil.str2PublicKey)
		  .exists(_ == key)	
        }
        .map(_.userName)
        .distinct
      // determine the user - if different accounts share the same key, tough luck
      val uniqueUserName =
        possibleUserNames match {
          case List(name) => Some(name)
          case _          => None
        }
      uniqueUserName.foreach(PublicKeyAuthenticator.putUserName(session, _))
      uniqueUserName.isDefined
    }
    else false
}
