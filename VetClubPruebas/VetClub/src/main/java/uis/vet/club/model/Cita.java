package uis.vet.club.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.sql.Date;
import java.sql.Time;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "cita", schema = "vetclub")

public class Cita implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_cita", nullable = false)
    private Long id_cita;

    @OneToOne
    @JoinColumn(name = "profesional", nullable = false)
    private Profesional profesional;

    @OneToOne
    @JoinColumn(name = "tipo_mascota", nullable = false)
    private TipoMascota tipoMascota;

    @OneToOne
    @JoinColumn(name = "tipo_proceso", nullable = false)
    private TipoProceso tipoProceso;

    @Column(name = "nickname")
    private String nickname;

    @Column(name = "fecha")
    private Date fecha;

    @Column(name = "hora")
    private Time hora;
}
