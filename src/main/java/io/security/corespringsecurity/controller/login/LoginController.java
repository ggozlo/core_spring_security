package io.security.corespringsecurity.controller.login;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    @GetMapping(value = {"/login","/api/login"})
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception,
                        Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);
        return "user/login/login";
    }

    @GetMapping("/logout") // get 방식의 로그아웃 직접 구현
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        // 로그아웃을 위한 서블릿을 인자로 받음
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // SecurityContextHolder 에서 인증객체를 받아옴
        if(authentication != null) {
            new SecurityContextLogoutHandler().logout(request,response,authentication);
            // 인증객체가 존재한다면 로그아웃 핸들러를 생성해 로그아웃처리
        }

        return "redirect:/login";
    }

    @GetMapping({"/denied", "/api/denied"})
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Account account = (Account) authentication.getPrincipal();
        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";

    }
}
