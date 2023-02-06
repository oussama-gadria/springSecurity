package com.workshop.springSecurity.config;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAthFilter extends OncePerRequestFilter {
    private UserDetailsService userDetailsService;
    private JwtUtils jwtUtils;
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
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

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
//Le code que vous avez fourni est pour une classe de filtre personnalisée dans Spring Security appelée JwtAuthFilter. Cette classe étend OncePerRequestFilter, qui est un filtre qui garantit une seule exécution du filtre logique par requête. La classe est responsable de l'authentification JWT pour les requêtes entrantes.
//
//Voici une explication étape par étape du code:
//
//Un champ privé userDetailsService est déclaré. Ce champ sera utilisé pour récupérer les informations d'utilisateur à partir d'une source telle que la base de données.
//
//La méthode doFilterInternal est définie pour fournir la logique de filtre personnalisée. Cette méthode sera appelée pour chaque requête entrante.
//
//La première chose que fait la méthode est de récupérer l'en-tête d'authentification de la requête en utilisant request.getHeader("Authorization").
//
//Les variables userEmail et jwtToken sont déclarées. Si l'en-tête d'authentification n'est pas présent ou ne commence pas par "Bearer", le filtre ne fera rien d'autre et le filterChain.doFilter sera appelé pour continuer à traiter la requête.
//
//Si l'en-tête d'authentification est présent, la valeur du jeton JWT est extraite en utilisant authHeader.substring(7).
//
//La méthode loadUserByUsername est appelée sur userDetailsService pour récupérer les informations de l'utilisateur en utilisant l'e-mail de l'utilisateur comme paramètre.
//
//La variable isTokenValid est déclarée comme fausse. Si elle est vraie, une nouvelle instance de UsernamePasswordAuthenticationToken est créée en utilisant les informations de l'utilisateur et les autorisations associées.
//
//Les détails de l'authentification sont définis en utilisant new WebAuthenticationDetailsSource().buildDetails(request).
//
//Le contexte d'authentification est défini en appelant SecurityContextHolder.getContext().setAuthentication(authenticationToken).
//
//Enfin, filterChain.doFilter est appelé pour continuer à traiter la requête.
///////////////////////////////////////////////////
//"filterChain.doFilter(request, response)" est une méthode qui fait partie du processus de filtrage en utilisant le pattern "Chain of Responsibility" (chaîne de responsabilité) dans Spring Security. Elle permet de transmettre la demande (request) et la réponse (response) au prochain filtre dans la chaîne, s'il en existe un.
//
//Dans ce cas, l'appel à cette méthode signifie que la demande et la réponse doivent être transmises au filtre suivant sans subir de traitement supplémentaire. Cela peut être utile dans des scénarios où aucune autorisation n'est requise pour accéder à la ressource demandée ou lorsque la requête ne contient pas d'en-tête d'authentification valide.