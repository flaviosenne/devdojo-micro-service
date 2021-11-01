package academy.devdojo.youtube.core.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class User implements AbstractEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @NotNull(message = "The field 'name' is mandatory")
    @Column(nullable = false)
    private String name;
    @NotNull(message = "The field 'password' is mandatory")
    @Column(nullable = false)
    private String password;
    @NotNull(message = "The field 'role' is mandatory")
    @Column(nullable = false)
    private String role = "USER";

    public User(@NotNull User user) {
        this.id = user.getId();
        this.name = user.getName();
        this.password = user.getPassword();
        this.role = user.getRole();
    }
}
