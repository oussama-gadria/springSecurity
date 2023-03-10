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
//Ce code configure un bean d'AuthenticationProvider pour Spring Security. L'AuthenticationProvider est responsable de la v??rification de l'authentification de l'utilisateur, en utilisant les informations stock??es dans une source de donn??es. Dans ce cas, l'objet DaoAuthenticationProvider est utilis??, qui v??rifie l'authentification en utilisant un objet UserDetailsService et un encodeur de mot de passe.
//
//La m??thode userDetailsService() renvoie un objet qui charge les d??tails de l'utilisateur ?? partir de la source de donn??es (dans cet exemple, une base de donn??es) pour que Spring Security puisse v??rifier l'authentification. La m??thode passwordEncoder() renvoie un objet qui est utilis?? pour encoder les mots de passe des utilisateurs stock??s dans la source de donn??es, afin de garantir la s??curit?? des mots de passe stock??s.
//
//En r??sum??, ce code configure l'AuthenticationProvider pour utiliser une source de donn??es (dans ce cas, une base de donn??es) pour la v??rification de l'authentification des utilisateurs, en utilisant un objet UserDetailsService pour charger les d??tails des utilisateurs et un encodeur de mot de passe pour garantir la s??curit?? des mots de passe stock??s.
    // le type de retour : Plus pr??cis??ment, l'interface AuthenticationProvider d??finit une m??thode authenticate(Authentication authentication) qui prend en entr??e un objet "Authentication" (qui encapsule les informations d'identification de l'utilisateur) et retourne un objet "Authentication" qui repr??sente l'utilisateur authentifi??. Si l'authentification ??choue, l'impl??mentation de la m??thode doit lever une exception de type "AuthenticationException".
    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }
//Avec cette modification, les mots de passe des utilisateurs seront hach??s avant d'??tre stock??s en base de donn??es, ce qui am??liore grandement la s??curit?? de l'application.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
//Cette m??thode d??finit un bean UserDetailsService qui fournit la logique n??cessaire pour charger les informations de l'utilisateur ?? partir de la base de donn??es. La m??thode cr??e une instance anonyme de UserDetailsService qui impl??mente la m??thode loadUserByUsername(String email). Cette m??thode est appel??e par le framework Spring Security lorsqu'il a besoin de charger les informations d'un utilisateur ?? partir de la base de donn??es.
//
//Dans cette m??thode, l'adresse e-mail est utilis??e pour trouver l'utilisateur dans la base de donn??es ?? l'aide d'une instance de UserDao qui est inject??e en tant que d??pendance. La m??thode findUserByEmail retourne un objet User qui impl??mente l'interface UserDetails, qui contient des informations telles que le nom d'utilisateur, le mot de passe et les r??les de l'utilisateur.
//
//Le r??le de cette m??thode est donc de fournir une impl??mentation de UserDetailsService qui peut ??tre utilis??e par Spring Security pour charger les informations d'utilisateur ?? partir de la base de donn??es lors de l'authentification et de l'autorisation.
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
//Ce code d??finit une classe de configuration de s??curit?? nomm??e SecurityConfig qui utilise @EnableWebSecurity pour activer la s??curit?? pour l'application.
//
//Ligne par ligne:
//
//@EnableWebSecurity : Cette annotation active la s??curit?? pour l'application en utilisant Spring Security.
//
//public class SecurityConfig : Cette ligne d??finit la classe de configuration de s??curit?? nomm??e SecurityConfig.
//
//@Bean : Cette annotation indique que la m??thode suivante sera enregistr??e en tant que Bean dans le conteneur de Beans de Spring.
//
//public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception : Cette m??thode d??finit une configuration de s??curit?? pour l'application en utilisant HttpSecurity. La m??thode prend en entr??e HttpSecurity et renvoie un objet de type SecurityFilterChain.
//
//httpSecurity.authorizeRequests() : Cette ligne d??finit les r??gles d'autorisation pour l'application.
//
//.anyRequest() : Cette ligne indique que toutes les requ??tes seront soumises ?? une authentification.
//
//.authenticated() : Cette ligne indique que seuls les utilisateurs authentifi??s auront acc??s ?? l'application.
//
//.and().httpBasic() : Cette ligne d??finit l'authentification de base HTTP comme m??thode d'authentification pour l'application.
//
//return httpSecurity.build() : Cette ligne renvoie la cha??ne de filtres de s??curit?? construite en utilisant httpSecurity.