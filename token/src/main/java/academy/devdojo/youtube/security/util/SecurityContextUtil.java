package academy.devdojo.youtube.security.util;

import academy.devdojo.youtube.core.model.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class SecurityContextUtil {
    private SecurityContextUtil(){

    }

    public static void setSecurityContext(SignedJWT signedJWT){
        try {

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            String name = claims.getSubject();

            if(name == null) throw new JOSEException("name missing  from JWT");

            List<String> authorities = claims.getStringListClaim("authorities");

            User user = User.builder()
                    .id(claims.getLongClaim("userId"))
                    .name(name)
                    .role(String.join(",", authorities))
                    .build();


            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(user,
                            null, createAuthorities(authorities));

            auth.setDetails(signedJWT.serialize());

            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        catch (Exception e){
            log.error("Error setting security context ",e);
            SecurityContextHolder.clearContext();
        }
    }

    private static List<SimpleGrantedAuthority> createAuthorities(List<String> authorities){
        return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
