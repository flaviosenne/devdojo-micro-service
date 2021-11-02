package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.youtube.core.model.User;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import academy.devdojo.youtube.security.token.creator.TokenCreator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;


@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUserNameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response){
        log.info("Attempting  authentication...");
        User user = new ObjectMapper().readValue(request.getInputStream(), User.class);

        if(user == null) throw new UsernameNotFoundException("Unable to retrieve the username  or password");

        log.info("Creating the authentication object for the user '{}' and calling UserDetailServiceImpl loadByUsername", user.getName());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getName(), user.getPassword(), Collections.emptyList());

        usernamePasswordAuthenticationToken.setDetails(user);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){

        log.info("Authentication was successful for the user '{}', generating JWE token", authentication.getName());

        SignedJWT signedJWT = tokenCreator.createSignedJWT(authentication);

        String tokenEncrypted = tokenCreator.encryptToken(signedJWT);

        log.info("Token generated successfully, adding it to the response header");

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, "+jwtConfiguration.getHeader().getName());

        response.addHeader
                (jwtConfiguration.getHeader().getName(),
                jwtConfiguration.getHeader().getPrefix() + tokenEncrypted);
    }

}
