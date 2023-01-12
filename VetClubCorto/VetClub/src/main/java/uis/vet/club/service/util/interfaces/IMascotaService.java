package uis.vet.club.service.util.interfaces;

import uis.vet.club.model.Mascota;

import java.util.List;

public interface IMascotaService {

    public List<Mascota> listarMascotas();

    public Mascota guardar(Mascota mascota);

    public void eliminar(Mascota mascota);

    public Mascota encontrarMasco(Mascota mascota);

}
