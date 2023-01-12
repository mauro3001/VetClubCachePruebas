package uis.vet.club.model;

import jakarta.persistence.*;
import lombok.*;
import net.minidev.json.annotate.JsonIgnore;
import org.aspectj.lang.annotation.control.CodeGenerationHint;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "rol", schema = "vetclub")
public class Rol implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @Column(name = "id_rol", nullable = false)
    private Long idRol;

    @Column(name = "nombre")
    private String nombre;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.LAZY, mappedBy = "rol")
    private Set<UsuarioRol> usuarioRoles = new HashSet<>();

}
