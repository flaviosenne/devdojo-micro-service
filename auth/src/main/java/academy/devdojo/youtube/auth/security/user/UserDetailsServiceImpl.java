package academy.devdojo.youtube.auth.security.user;

import academy.devdojo.youtube.core.model.User;
import academy.devdojo.youtube.core.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.Collection;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String name){
        log.info("Searching in the DB the user  by username '{}' ", name);
        User user = repository.findByName(name)
                .orElseThrow(()-> new UsernameNotFoundException("Application user by name "+ name+ " is not found"));

        log.info("Application user found '{}' ", user);

        return new CustomUserDetails(user);
    }

    private static final class CustomUserDetails extends User implements UserDetails {

        CustomUserDetails(@NotNull User user){
            super(user);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_"+this.getRole());
        }

        @Override
        public String getUsername() {
            return null;
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
