package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가 정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        //인증 정책
        http
                .formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    System.out.println("authentication : " + authentication.getName());
                    httpServletResponse.sendRedirect("/");
                })
                .failureHandler((httpServletRequest, httpServletResponse, e) -> {
                    System.out.println("exception : " + e.getMessage());
                    httpServletResponse.sendRedirect("/login");
                })
            .permitAll()
        ;

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    HttpSession session = httpServletRequest.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler(
                        (httpServletRequest, httpServletResponse, authentication)
                                -> httpServletResponse.sendRedirect("/login")
                )
                .deleteCookies("remember");

        http
                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);

        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true);

        http
                .sessionManagement()
                .sessionFixation().none();



    }
}
