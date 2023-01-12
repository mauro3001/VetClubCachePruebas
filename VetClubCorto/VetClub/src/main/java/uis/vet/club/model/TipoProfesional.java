package uis.vet.club.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "tipo_profesional", schema = "vetclub")

public class TipoProfesional implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_tipo_profesional", nullable = false)
    private Long id_tipo_profesional;

    @Column(name = "profesion")
    private String profesion;

    @Column(name = "descripcion")
    private String descripcion;
}
