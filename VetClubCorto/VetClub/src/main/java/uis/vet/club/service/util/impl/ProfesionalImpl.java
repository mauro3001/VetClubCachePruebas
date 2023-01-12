package uis.vet.club.service.util.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uis.vet.club.model.Profesional;
import uis.vet.club.repository.util.IProfesionalRespository;
import uis.vet.club.service.util.interfaces.IProfesionalService;

import java.util.List;

@Service
public class ProfesionalImpl implements IProfesionalService {

    @Autowired
    private IProfesionalRespository profesionalRespository;

    @Override
    @Transactional(readOnly = true)
    public List<Profesional> listarPro() {
        return (List<Profesional>) profesionalRespository.findAll();
    }

    @Override
    @Transactional
    public Profesional guardar(Profesional profesional) {
        profesionalRespository.save(profesional);
        return profesional;
    }

    @Override
    @Transactional
    public void eliminar(Profesional profesional) {
        profesionalRespository.delete(profesional);

    }

    @Override
    @Transactional(readOnly = true)
    public Profesional encontrarPro(Profesional profesional) {
        return profesionalRespository.findById(profesional.getId_profesional()).orElse(null);
    }
}
