package com.workshop.springSecurity.config;

import com.workshop.springSecurity.dao.UserDao;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@EnableWebSecurity
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    @Autowired
    private JwtAthFilter jwtAthFilter;
    private UserDao userDao;

    @Bean
    public JwtAthFilter jwtAthFilter() {
        return new JwtAthFilter();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAthFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); //not crypted
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userDao.findUserByEmail(email);
            }
        };
    }
}
//Ce code définit une classe de configuration de sécurité nommée SecurityConfig qui utilise @EnableWebSecurity pour activer la sécurité pour l'application.
//
//Ligne par ligne:
//
//@EnableWebSecurity : Cette annotation active la sécurité pour l'application en utilisant Spring Security.
//
//public class SecurityConfig : Cette ligne définit la classe de configuration de sécurité nommée SecurityConfig.
//
//@Bean : Cette annotation indique que la méthode suivante sera enregistrée en tant que Bean dans le conteneur de Beans de Spring.
//
//public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception : Cette méthode définit une configuration de sécurité pour l'application en utilisant HttpSecurity. La méthode prend en entrée HttpSecurity et renvoie un objet de type SecurityFilterChain.
//
//httpSecurity.authorizeRequests() : Cette ligne définit les règles d'autorisation pour l'application.
//
//.anyRequest() : Cette ligne indique que toutes les requêtes seront soumises à une authentification.
//
//.authenticated() : Cette ligne indique que seuls les utilisateurs authentifiés auront accès à l'application.
//
//.and().httpBasic() : Cette ligne définit l'authentification de base HTTP comme méthode d'authentification pour l'application.
//
//return httpSecurity.build() : Cette ligne renvoie la chaîne de filtres de sécurité construite en utilisant httpSecurity.