package uis.vet.club.service.util.interfaces;

import uis.vet.club.model.Usuario;
import uis.vet.club.model.UsuarioRol;

import java.util.List;
import java.util.Set;

public interface IUsuarioService {
    public List<Usuario> listarUsuarios();

    public Usuario guardar(Usuario usuario, Set<UsuarioRol> usuarioRoles) throws Exception;

    public void eliminar(Usuario usuario);

    public Usuario encontrarUsuario(Usuario usuario);
}
