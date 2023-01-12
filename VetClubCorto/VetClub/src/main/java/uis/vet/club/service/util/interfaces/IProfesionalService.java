package uis.vet.club.service.util.interfaces;

import uis.vet.club.model.Profesional;

import java.util.List;

public interface IProfesionalService {

    public List<Profesional> listarPro();

    public Profesional guardar(Profesional profesional);

    public void eliminar(Profesional profesional);

    public Profesional encontrarPro(Profesional profesional);

}
