package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인가 정책
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        //인증 정책
        http
                .formLogin()
                .successHandler((httpServletRequest, httpServletResponse, authentication) -> {
                    RequestCache requestCache = new HttpSessionRequestCache();
                    SavedRequest savedRequest = requestCache.getRequest(httpServletRequest, httpServletResponse);
                    String redirectUrl = savedRequest.getRedirectUrl();
                    httpServletResponse.sendRedirect(redirectUrl);
                })
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
                .exceptionHandling()
                .authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendRedirect("/login"))
                .accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> httpServletResponse.sendRedirect("/denied"));

        http
                .sessionManagement()
                .sessionFixation().none();



    }
}
