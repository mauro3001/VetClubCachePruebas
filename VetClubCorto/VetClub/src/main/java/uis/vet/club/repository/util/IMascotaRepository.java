package uis.vet.club.repository.util;

import org.springframework.data.jpa.repository.JpaRepository;
import uis.vet.club.model.Mascota;

public interface IMascotaRepository extends JpaRepository<Mascota, Long> {
}
