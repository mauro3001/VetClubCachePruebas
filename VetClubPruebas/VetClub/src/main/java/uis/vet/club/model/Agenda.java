package uis.vet.club.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "agenda", schema = "vetclub")

public class Agenda implements Serializable {
    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id_agenda", nullable = false)
    private Long id_agenda;

    @OneToOne
    @JoinColumn(name = "cita", nullable = false)
    private Cita cita;
}
