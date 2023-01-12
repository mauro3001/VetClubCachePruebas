package uis.vet.club.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Entity
@Data
@Table(name = "tipo_mascota", schema = "vetclub")
@AllArgsConstructor
@NoArgsConstructor
public class TipoMascota implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_tipo_mascota", nullable = false)
    private Long id_tipo_mascota;

    @Column(name = "animal")
    private String animal;

}
