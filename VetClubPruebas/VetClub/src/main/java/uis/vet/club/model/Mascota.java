package uis.vet.club.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.minidev.json.annotate.JsonIgnore;

import java.io.Serializable;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Mascota implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_mascota", nullable = false)
    private Long id_mascota;

    @OneToOne
    @JoinColumn(name = "tipo_mascota")
    private TipoMascota tipoMascota;

    /*Por si se quiere solamente el id_tipo_mascota
    @Column(name = "tipo_mascota")
    private Long tipoMascota;*/


    @Column(name = "nombre")
    private String nombre;

    @Column(name = "raza")
    private String raza;

    @Column(name = "historial")
    private String historial;
}
