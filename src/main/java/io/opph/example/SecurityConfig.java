package io.opph.example;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    @SuppressWarnings("deprecation")
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build())
                .withUser(User.withDefaultPasswordEncoder().username("admin").password("admin").roles("USER", "ADMIN").build());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and().formLogin()
                .and().httpBasic();
    }
}
