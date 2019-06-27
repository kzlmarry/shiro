package com.cplatform.cucme.shiro.config;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.cplatform.cucme.module.webUser.entity.WebUser;
import com.cplatform.cucme.module.webUser.entity.vo.AuthVo;
import com.cplatform.cucme.module.webUser.service.SysPermService;
import com.cplatform.cucme.module.webUser.service.SysRoleService;
import com.cplatform.cucme.module.webUser.service.WebUserService;
import com.google.common.collect.Maps;

/**
 * 这个类是参照JDBCRealm写的，主要是自定义了如何查询用户信息，如何查询用户的角色和权限，如何校验密码等逻辑
 */
public class UserRealm extends AuthorizingRealm {

	private static final Logger log = LoggerFactory.getLogger(UserRealm.class);

	@Autowired
	private WebUserService webUserService;

	@Autowired
	private SysRoleService roleService;

	@Autowired
	private SysPermService permService;

//	@Override
//	public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
//		// 设置用于匹配密码的CredentialsMatcher
//		HashedCredentialsMatcher hashMatcher = new HashedCredentialsMatcher();
//		hashMatcher.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
//		hashMatcher.setStoredCredentialsHexEncoded(false);
//		hashMatcher.setHashIterations(1024);
//		super.setCredentialsMatcher(hashMatcher);
//	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// null usernames are invalid
		if (principals == null) {
			throw new AuthorizationException("PrincipalCollection method argument cannot be null.");
		}

		WebUser user = (WebUser) getAvailablePrincipal(principals);
		Set<AuthVo> roles = user.getRoles();
		Set<AuthVo> perms = user.getPerms();
		log.info("获取角色权限信息: roles: {}, perms: {}", roles, perms);

		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.setRoles(roles.stream().map(AuthVo::getVal).collect(Collectors.toSet()));
		info.setStringPermissions(perms.stream().map(AuthVo::getVal).collect(Collectors.toSet()));
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String username = upToken.getUsername();

		if (username == null) {
			throw new AccountException("用户名不能为空");
		}
		Map<String, Object> condition = Maps.newHashMap();
		condition.put("userName", username);
		WebUser userDB = webUserService.findOne(condition, true);
		if (userDB == null) {
			throw new UnknownAccountException("找不到用户（" + username + "）的帐号信息");
		}else {
			
		}

		// 查询用户的角色和权限存到SimpleAuthenticationInfo中，这样在其它地方
		// SecurityUtils.getSubject().getPrincipal()就能拿出用户的所有信息，包括角色和权限
		
//		Map<String, Object> condition1 = Maps.newHashMap();
//		condition1.put("rid", userDB.getId());
//		Map<String, Object> condition2 = Maps.newHashMap();
//		condition2.put("pval_id", userDB.getId());
//		Set<AuthVo> roles = (Set<AuthVo>) roleService.findOne(condition1, true);
//		Set<AuthVo> perms = (Set<AuthVo>) permService.findOne(condition2, true);
//		userDB.getRoles().addAll(roles);
//		userDB.getPerms().addAll(perms);

		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(userDB, userDB.getPassword(), getName());
//		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo();
		//加密
//		if (userDB.getSalt() != null) {
//			info.setCredentialsSalt(ByteSource.Util.bytes(userDB.getSalt()));
//		}
		
		
		
		return info;

	}

}
