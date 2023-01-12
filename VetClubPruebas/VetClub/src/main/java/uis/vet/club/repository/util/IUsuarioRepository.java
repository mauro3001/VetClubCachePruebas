package uis.vet.club.repository.util;

import org.springframework.data.jpa.repository.JpaRepository;
import uis.vet.club.model.Usuario;

public interface IUsuarioRepository extends JpaRepository<Usuario, Long> {
    public Usuario findByUsername(String username);
}
