package uis.vet.club.service.util.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import uis.vet.club.model.Usuario;
import uis.vet.club.model.UsuarioRol;
import uis.vet.club.repository.util.IRolRepository;
import uis.vet.club.repository.util.IUsuarioRepository;
import uis.vet.club.service.util.interfaces.IUsuarioService;

import java.util.List;
import java.util.Set;

@Service
public class UsuarioImpl implements IUsuarioService {

    @Autowired
    private IUsuarioRepository usuarioRepository;

    @Autowired
    private IRolRepository rolRepository;

    @Override
    @Transactional(readOnly = true)
    public List<Usuario> listarUsuarios() {
        return (List<Usuario>) usuarioRepository.findAll();
    }

    @Override
    @Transactional
    public Usuario guardar(Usuario usuario, Set<UsuarioRol> usuarioRoles) throws Exception {
        Usuario usuario1 = usuarioRepository.findByUsername(usuario.getUsername());

        if(usuario1 != null){
            System.out.println("Ese nombre de usuario ya existe");
            throw new Exception("Ese nombre de usuario ya existe");
        }else{
            for (UsuarioRol usuarioRol: usuarioRoles){
                rolRepository.save(usuarioRol.getRol());

            }
            usuario.getUsuarioRoles().addAll(usuarioRoles);
            usuario1 = usuarioRepository.save(usuario);
        }
        return usuario1;
    }

    @Override
    @Transactional
    public void eliminar(Usuario usuario) {
        usuarioRepository.delete(usuario);
    }

    @Override
    @Transactional(readOnly = true)
    public Usuario encontrarUsuario(Usuario usuario) {
        return usuarioRepository.findById(usuario.getId_usuario()).orElse(null);
    }
}
