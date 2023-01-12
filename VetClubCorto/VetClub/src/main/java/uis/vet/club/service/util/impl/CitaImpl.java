package uis.vet.club.service.util.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uis.vet.club.model.Cita;
import uis.vet.club.repository.util.ICitaRepository;
import uis.vet.club.service.util.interfaces.ICitaService;

import java.util.List;

@Service
public class CitaImpl implements ICitaService {

    @Autowired
    private ICitaRepository citaRepository;

    @Override
    @Transactional(readOnly = true)
    public List<Cita> listarCitas() {
        return citaRepository.findAll();
    }

    @Override
    @Transactional
    public Cita guardarCita(Cita cita) {
        citaRepository.save(cita);
        return cita;
    }

    @Override
    @Transactional
    public void eliminarCita(Cita cita) {
        citaRepository.delete(cita);
    }

    @Override
    @Transactional(readOnly = true)
    public Cita encontrarCita(Cita cita) {
        return citaRepository.findById(cita.getId_cita()).orElse(null);
    }
}
