package academy.devdojo.youtube.auth.security.filter;

import academy.devdojo.youtube.core.model.User;
import academy.devdojo.youtube.core.property.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUserNameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;

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

        SignedJWT signedJWT = createSignedJWT(authentication);

        String tokenEncrypted = encryptToken(signedJWT);

        log.info("Token generated successfully, adding it to the response header");

        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, "+jwtConfiguration.getHeader().getName());

        response.addHeader
                (jwtConfiguration.getHeader().getName(),
                jwtConfiguration.getHeader().getPrefix() + tokenEncrypted);
    }

    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication authentication){
        log.info("Starting to create the signed JWT");
        User user = (User) authentication.getPrincipal();

        JWTClaimsSet jwtClaimsSet = createJWTClaimsSet(authentication, user);

        KeyPair rsaKeys = generateKeyPair();

        log.info("Building JWK from RSA Keys");

        JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic())
                .keyID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader
                .Builder(JWSAlgorithm.RS256)
                .jwk(jwk).type(JOSEObjectType.JWT)
                .build(), jwtClaimsSet);

        log.info("Signing the token with the private RSA key");

        RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());

        signedJWT.sign(signer);

        log.info("Serialized token '{}' ", signedJWT.serialize());

        return signedJWT;

    }

    private JWTClaimsSet createJWTClaimsSet(Authentication authentication, User user){
        log.info("Creating the JwtClaimsSet object for '{}' ", user);
        return new JWTClaimsSet.Builder()
                .subject(user.getName())
                .claim("authorities", authentication.getAuthorities()
                        .stream().map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000) ))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair(){
        log.info("Generating RSA 2048 bits Keys");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        return generator.genKeyPair();
    }

    private String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encryptToken method");

        DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEObject jwtObject= new JWEObject(new JWEHeader.Builder(
                JWEAlgorithm.DIR,
                EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));


        log.info("Encrypt token with system's private key");

        jwtObject.encrypt(directEncrypter);

        log.info("Token encrypted");

        return jwtObject.serialize();
    }
}
