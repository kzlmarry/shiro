package com.cplatform.cucme.controller;

import java.io.Serializable;
import java.util.UUID;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.cplatform.cucme.module.util.Codes;
import com.cplatform.cucme.module.util.Json;
import com.cplatform.cucme.module.webUser.entity.WebUser;

/**
 * created by cplatform at 2019/6/26 17:26<br>
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    /**
     * shiro.loginUrl映射到这里，我在这里直接抛出异常交给GlobalExceptionHandler来统一返回json信息，
     * 您也可以在这里直接返回json，不过这样子就跟GlobalExceptionHandler中返回的json重复了。
     *
     * @return
     */
    @RequestMapping("/page/401")
    @ResponseBody
    public Json page401() {
        throw new UnauthenticatedException();
    }

    /**
     * shiro.unauthorizedUrl映射到这里。由于约定了url方式只做鉴权控制，不做权限访问控制，
     * 也就是说在ShiroConfig中如果没有做roles[js],perms[mvn:install]这样的权限访问控制配置的话，是不会跳转到这里的。
     *
     * @return
     */
    @RequestMapping("/page/403")
    public Json page403() {
        throw new UnauthorizedException();
    }

    /**
     * 登录成功跳转到这里，直接返回json。但是实际情况是在login方法中登录成功后返回json了。
     *
     * @return
     */
    @RequestMapping("/page/index")
    public Json pageIndex() {
        return new Json("index", true, 1, "index page", null);
    }

    /**
     * 登录接口，由于UserService中是模拟返回用户信息的， 所以用户名随意，密码123456
     *
     * @param body
     * @return
     */
    @RequestMapping("/login")
    public Json login(WebUser webUser) {

        String oper = "user login";
        String uname = webUser.getUserName();
        String pwd = webUser.getPassword();

        if (StringUtils.isEmpty(uname)) {
            return Json.fail(oper, "用户名不能为空");
        }
        if (StringUtils.isEmpty(pwd)) {
            return Json.fail(oper, "密码不能为空");
        }

        Subject currentUser = SecurityUtils.getSubject();
        try {
            // 登录
            currentUser.login(new UsernamePasswordToken(uname, pwd));
            // 从session取出用户信息
            WebUser user = (WebUser) currentUser.getPrincipal();
            if (user == null) {
                throw new AuthenticationException();
            }
            log.info("user login: {}, sessionId: {}", user.getUserName(), currentUser.getSession().getId());
            // 返回登录用户的信息给前台，含用户的所有角色和权限
            return  Json.succ(oper).data("token", UUID.randomUUID().toString()).data("uid", user.getId()).data("member", user.getMember())
                    .data("userName", user.getUserName()).data("shopId", user.getShopId()).data("sessionId", currentUser.getSession().getId());
        } catch (UnknownAccountException uae) {
            log.warn("用户帐号不正确");
            return Json.fail(oper, "用户帐号或密码不正确");

        } catch (IncorrectCredentialsException ice) {
            log.warn("用户密码不正确");
            return Json.fail(oper, "用户帐号或密码不正确");

        } catch (LockedAccountException lae) {
            log.warn("用户帐号被锁定");
            return Json.fail(oper, "用户帐号被锁定不可用");
        } catch (AuthenticationException ae) {
            log.warn("登录出错");
            return Json.fail(oper, "登录失败：" + ae.getMessage());
        }
    }
    /**
     * 退出
     * @return
     */
    @PostMapping("/logout")
    public Json logout() {
        String oper = "user logout";
        log.info("{}", oper);
        SecurityUtils.getSubject().logout();
        return new Json(oper);
    }

    @GetMapping("/info")
    public Json info() {
        String oper = "get user info";

        Subject subject = SecurityUtils.getSubject();

        Serializable sessionId = subject.getSession().getId();
        log.info("{}, sessionId: {}", oper, sessionId);

        // 从session取出用户信息
        WebUser user = (WebUser) subject.getPrincipal();
        if (user == null) {
            // 告知前台，登录失效
        	
            return new Json(oper, false, Codes.SESSION_TIMEOUT, "", null);
        } else {
            // 返回登录用户的信息给前台，含用户的所有角色和权限
            return Json.succ(oper).data("token", UUID.randomUUID().toString()).data("uid", user.getId()).data("member", user.getMember())
                    .data("userName", user.getUserName()).data("shopId", user.getShopId());
            
        }

    }
    
	

}
