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
@Table(name = "profesional", schema = "vetclub")
public class Profesional implements Serializable {
    private static final long serialversionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_profesional", nullable = false)
    private Long id_profesional;

    //Metodo para solo pasar el identificador del tipoProfesional
    @Column(name = "tipo_profesional", nullable = false)
    private Long tipoProfesional;

    /*Metodo para poder pasar el modelo entero
    @OneToOne
    @JoinColumn(name = "tipo_profesional", nullable = false)
    private TipoProfesional tipoProfesional;*/

    @Column(name = "nombre")
    private String nombre;

    @Column(name = "correo")
    private String correo;

    @Column(name = "nickname")
    private String nickname;

}
