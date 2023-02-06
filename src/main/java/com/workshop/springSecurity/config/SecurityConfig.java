package com.workshop.springSecurity.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAthFilter jwtAthFilter;
    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "oussamagadria@gmail.com",
                    "password",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
            ),
            new User(
                    "gadriaoussama@gmail.com",
                    "password",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))
            )
    );
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)throws Exception{
        httpSecurity.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(jwtAthFilter, UsernamePasswordAuthenticationFilter.class);// her we said to spring to execute jwtAthFilter before UsernamePasswordAuthenticationFilter filtre

        return httpSecurity.build();
    }
    @Bean
    public UserDetailsService userDetailsService(){
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return   APPLICATION_USERS
                        .stream()
                        .filter(u -> u.getUsername().equals(email))
                        .findFirst()
                        .orElseThrow(() -> new UsernameNotFoundException("No User Was Found"));
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