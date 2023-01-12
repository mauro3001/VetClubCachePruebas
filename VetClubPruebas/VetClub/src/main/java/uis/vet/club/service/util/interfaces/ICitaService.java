package uis.vet.club.service.util.interfaces;

import uis.vet.club.model.Cita;

import java.util.List;

public interface ICitaService {
    public List<Cita> listarCitas();

    public Cita guardarCita(Cita cita);

    public void eliminarCita(Cita cita);

    public Cita encontrarCita(Cita cita);
}
