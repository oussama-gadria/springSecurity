package com.workshop.springSecurity.config;

import com.workshop.springSecurity.dao.UserDao;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity // pour activer la configuration de spring security
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final JwtAthFilter jwtAthFilter;
    private final UserDao userDao;




    @Bean
    protected SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .authorizeRequests()
                .antMatchers("/**/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAthFilter, UsernamePasswordAuthenticationFilter.class);
        return  httpSecurity.build();
    }
//Ce code configure un bean d'AuthenticationProvider pour Spring Security. L'AuthenticationProvider est responsable de la vérification de l'authentification de l'utilisateur, en utilisant les informations stockées dans une source de données. Dans ce cas, l'objet DaoAuthenticationProvider est utilisé, qui vérifie l'authentification en utilisant un objet UserDetailsService et un encodeur de mot de passe.
//
//La méthode userDetailsService() renvoie un objet qui charge les détails de l'utilisateur à partir de la source de données (dans cet exemple, une base de données) pour que Spring Security puisse vérifier l'authentification. La méthode passwordEncoder() renvoie un objet qui est utilisé pour encoder les mots de passe des utilisateurs stockés dans la source de données, afin de garantir la sécurité des mots de passe stockés.
//
//En résumé, ce code configure l'AuthenticationProvider pour utiliser une source de données (dans ce cas, une base de données) pour la vérification de l'authentification des utilisateurs, en utilisant un objet UserDetailsService pour charger les détails des utilisateurs et un encodeur de mot de passe pour garantir la sécurité des mots de passe stockés.
    // le type de retour : Plus précisément, l'interface AuthenticationProvider définit une méthode authenticate(Authentication authentication) qui prend en entrée un objet "Authentication" (qui encapsule les informations d'identification de l'utilisateur) et retourne un objet "Authentication" qui représente l'utilisateur authentifié. Si l'authentification échoue, l'implémentation de la méthode doit lever une exception de type "AuthenticationException".
    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
//Avec cette modification, les mots de passe des utilisateurs seront hachés avant d'être stockés en base de données, ce qui améliore grandement la sécurité de l'application.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
//Cette méthode définit un bean UserDetailsService qui fournit la logique nécessaire pour charger les informations de l'utilisateur à partir de la base de données. La méthode crée une instance anonyme de UserDetailsService qui implémente la méthode loadUserByUsername(String email). Cette méthode est appelée par le framework Spring Security lorsqu'il a besoin de charger les informations d'un utilisateur à partir de la base de données.
//
//Dans cette méthode, l'adresse e-mail est utilisée pour trouver l'utilisateur dans la base de données à l'aide d'une instance de UserDao qui est injectée en tant que dépendance. La méthode findUserByEmail retourne un objet User qui implémente l'interface UserDetails, qui contient des informations telles que le nom d'utilisateur, le mot de passe et les rôles de l'utilisateur.
//
//Le rôle de cette méthode est donc de fournir une implémentation de UserDetailsService qui peut être utilisée par Spring Security pour charger les informations d'utilisateur à partir de la base de données lors de l'authentification et de l'autorisation.
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