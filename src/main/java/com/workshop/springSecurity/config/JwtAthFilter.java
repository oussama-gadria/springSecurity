package com.workshop.springSecurity.config;

import com.workshop.springSecurity.dao.UserDao;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAthFilter extends OncePerRequestFilter {
    private final UserDao userDao;
    private final JwtUtils jwtUtils;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String userEmail;
        final String jwtToken;
        if (authHeader == null || !authHeader.startsWith("Bearer")) {
            filterChain.doFilter(request, response);
            return;
        }
        jwtToken = authHeader.substring(7);
        userEmail =jwtUtils.extractUsername(jwtToken);
        if ((userEmail != null) && (SecurityContextHolder.getContext().getAuthentication() == null)) {
            UserDetails userDetails = userDao.findUserByEmail(userEmail);

            if (jwtUtils.validateToken(jwtToken,userDetails)) {
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            filterChain.doFilter(request, response);


        }
    }
}
//Le code que vous avez fourni est pour une classe de filtre personnalis??e dans Spring Security appel??e JwtAuthFilter. Cette classe ??tend OncePerRequestFilter, qui est un filtre qui garantit une seule ex??cution du filtre logique par requ??te. La classe est responsable de l'authentification JWT pour les requ??tes entrantes.
//
//Voici une explication ??tape par ??tape du code:
//
//Un champ priv?? userDetailsService est d??clar??. Ce champ sera utilis?? pour r??cup??rer les informations d'utilisateur ?? partir d'une source telle que la base de donn??es.
//
//La m??thode doFilterInternal est d??finie pour fournir la logique de filtre personnalis??e. Cette m??thode sera appel??e pour chaque requ??te entrante.
//
//La premi??re chose que fait la m??thode est de r??cup??rer l'en-t??te d'authentification de la requ??te en utilisant request.getHeader("Authorization").
//
//Les variables userEmail et jwtToken sont d??clar??es. Si l'en-t??te d'authentification n'est pas pr??sent ou ne commence pas par "Bearer", le filtre ne fera rien d'autre et le filterChain.doFilter sera appel?? pour continuer ?? traiter la requ??te.
//
//Si l'en-t??te d'authentification est pr??sent, la valeur du jeton JWT est extraite en utilisant authHeader.substring(7).
//
//La m??thode loadUserByUsername est appel??e sur userDetailsService pour r??cup??rer les informations de l'utilisateur en utilisant l'e-mail de l'utilisateur comme param??tre.
//
//La variable isTokenValid est d??clar??e comme fausse. Si elle est vraie, une nouvelle instance de UsernamePasswordAuthenticationToken est cr????e en utilisant les informations de l'utilisateur et les autorisations associ??es.
//
//Les d??tails de l'authentification sont d??finis en utilisant new WebAuthenticationDetailsSource().buildDetails(request).
//
//Le contexte d'authentification est d??fini en appelant SecurityContextHolder.getContext().setAuthentication(authenticationToken).
//
//Enfin, filterChain.doFilter est appel?? pour continuer ?? traiter la requ??te.
///////////////////////////////////////////////////
//"filterChain.doFilter(request, response)" est une m??thode qui fait partie du processus de filtrage en utilisant le pattern "Chain of Responsibility" (cha??ne de responsabilit??) dans Spring Security. Elle permet de transmettre la demande (request) et la r??ponse (response) au prochain filtre dans la cha??ne, s'il en existe un.
//
//Dans ce cas, l'appel ?? cette m??thode signifie que la demande et la r??ponse doivent ??tre transmises au filtre suivant sans subir de traitement suppl??mentaire. Cela peut ??tre utile dans des sc??narios o?? aucune autorisation n'est requise pour acc??der ?? la ressource demand??e ou lorsque la requ??te ne contient pas d'en-t??te d'authentification valide.