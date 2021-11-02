package academy.devdojo.youtube.security.token.creator;

import academy.devdojo.youtube.core.model.User;
import academy.devdojo.youtube.core.property.JwtConfiguration;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {
    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public SignedJWT createSignedJWT(Authentication authentication){
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

    public String encryptToken(SignedJWT signedJWT) throws JOSEException {
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
