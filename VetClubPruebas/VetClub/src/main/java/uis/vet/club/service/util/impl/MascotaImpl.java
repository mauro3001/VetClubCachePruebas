package uis.vet.club.service.util.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uis.vet.club.model.Mascota;
import uis.vet.club.repository.util.IMascotaRepository;
import uis.vet.club.service.util.interfaces.IMascotaService;

import java.util.List;

@Service
public class MascotaImpl implements IMascotaService {

    @Autowired
    private IMascotaRepository mascotaRepository;
    @Override
    @Transactional(readOnly = true)
    public List<Mascota> listarMascotas() {
        return (List<Mascota>) mascotaRepository.findAll();
    }

    @Override
    @Transactional
    public Mascota guardar(Mascota mascota) {
        mascotaRepository.save(mascota);
        return mascota;
    }

    @Override
    @Transactional
    public void eliminar(Mascota mascota) {
        mascotaRepository.delete(mascota);
    }

    @Override
    @Transactional(readOnly = true)
    public Mascota encontrarMasco(Mascota mascota) {
        return mascotaRepository.findById(mascota.getId_mascota()).orElse(null);
    }
}
