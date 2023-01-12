package uis.vet.club.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import uis.vet.club.model.*;
import uis.vet.club.service.util.interfaces.ICitaService;
import uis.vet.club.service.util.interfaces.IMascotaService;
import uis.vet.club.service.util.interfaces.IProfesionalService;
import uis.vet.club.service.util.interfaces.IUsuarioService;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@RestController
@CrossOrigin(origins = "http://localhost:4200")
@RequestMapping("/api")
@Slf4j
public class VetController {

    @Autowired
    private IUsuarioService usuarioService;

    @Autowired
    private IProfesionalService profesionalService;

    @Autowired
    private IMascotaService mascotaService;

    @Autowired
    private ICitaService citaService;

    @GetMapping("/usuarios")
    public List<Usuario> listarUsuarios(){
        return usuarioService.listarUsuarios();
    }

    @PostMapping("/usuario/agregar")
    public ResponseEntity<Usuario> agregar(@RequestBody Usuario usuario) throws Exception {
        Set<UsuarioRol> usuarioRoles = new HashSet<>();

        Rol rol = new Rol();
        rol.setIdRol(1L);
        rol.setNombre("ADMIN");

        UsuarioRol usuarioRol = new UsuarioRol();
        usuarioRol.setUsuario(usuario);
        usuarioRol.setRol(rol);

        //usuarioRoles.add(usuarioRol);

        Usuario usr = usuarioService.guardar(usuario,usuarioRoles);
        return new ResponseEntity<Usuario>(usr, HttpStatus.OK);
    }

    @GetMapping("/usuario/{id_usuario}")
    public Usuario encontrar(@PathVariable Usuario id_usuario){
        return usuarioService.encontrarUsuario(id_usuario);
    }

    /*
    @PutMapping("/usuario/{id_usuario}")
    public ResponseEntity<Usuario> actualizarUsuario(@PathVariable Usuario id_usuario, @RequestBody Usuario detalles){
        Usuario usuario = usuarioService.encontrarUsuario(id_usuario);

        usuario.setCorreo(detalles.getCorreo());
        usuario.setNombre(detalles.getNombre());
        usuario.setNickname(detalles.getNickname());
        usuario.setTelefono(detalles.getTelefono());

        Usuario usuarioActualizado = usuarioService.guardar(usuario);
        return new ResponseEntity<Usuario>(usuarioActualizado, HttpStatus.OK);
    }*/
    @GetMapping("/usuario/eliminar/{id_usuario}")
    public ResponseEntity<Usuario> eliminar(@PathVariable Usuario id_usuario){
        Usuario usr = usuarioService.encontrarUsuario(id_usuario);
        if(usr != null){
            usuarioService.eliminar(id_usuario);
        }else{
            return new ResponseEntity<Usuario>(usr, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<Usuario>(usr, HttpStatus.OK);
    }

    @GetMapping("/profesionales")
    public List<Profesional> listarProfesionales(){
        return profesionalService.listarPro();
    }

    @PostMapping("/profesional/agregar")
    public ResponseEntity<Profesional> agregarPro(@RequestBody Profesional profesional){
        Profesional pro = profesionalService.guardar(profesional);
        return new ResponseEntity<Profesional>(pro, HttpStatus.OK);
    }

    @GetMapping("/profesional/{id_profesional}")
    public Profesional encontrarPro(@PathVariable Profesional id_profesional){
        return profesionalService.encontrarPro(id_profesional);
    }

    @PutMapping("/profesional/{id_profesional}")
    public ResponseEntity<Profesional> acutalizarPro(@PathVariable Profesional id_profesional, @RequestBody Profesional detalles){
        Profesional pro1 = profesionalService.encontrarPro(id_profesional);

        pro1.setTipoProfesional(pro1.getTipoProfesional());
        pro1.setNombre(detalles.getNombre());
        pro1.setNickname(detalles.getNickname());
        pro1.setCorreo(detalles.getNickname());

        Profesional proActualizado = profesionalService.guardar(pro1);
        return new ResponseEntity<Profesional>(proActualizado,HttpStatus.OK);
    }
    @GetMapping("/profesional/eliminar/{id_profesional}")
    public ResponseEntity<Profesional> eliminarPro(@PathVariable Profesional id_profesional){
        Profesional pro = profesionalService.encontrarPro(id_profesional);
        if(pro != null){
            profesionalService.eliminar(id_profesional);
        }else{
            return new ResponseEntity<Profesional>(pro, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<Profesional>(pro, HttpStatus.OK);
    }

    @GetMapping("/mascotas")
    public List<Mascota> listarMascotas(){
        return mascotaService.listarMascotas();
    }

    @PostMapping(value = "/mascota/agregar")
    @ResponseBody
    public ResponseEntity<Mascota> agregarMasco(@RequestBody Mascota mascota){
        Mascota masco = mascotaService.guardar(mascota);
        return new ResponseEntity<Mascota>(masco, HttpStatus.CREATED);
    }

    @GetMapping("/mascota/{id_mascota}")
    public Mascota encontrarMasco(@PathVariable Mascota id_mascota){
        return mascotaService.encontrarMasco(id_mascota);
    }

    @PutMapping("/mascota/{id_mascota}")
    public ResponseEntity<Mascota> actualizarMasco(@PathVariable Mascota id_mascota, @RequestBody Mascota detalles){
        Mascota masco = mascotaService.encontrarMasco(id_mascota);

        masco.setTipoMascota(detalles.getTipoMascota());
        masco.setNombre(detalles.getNombre());
        masco.setRaza(detalles.getRaza());
        masco.setHistorial(detalles.getHistorial());

        Mascota mascoAcutualizada = mascotaService.guardar(masco);
        return new ResponseEntity<Mascota>(mascoAcutualizada, HttpStatus.OK);
    }

    @GetMapping("/mascota/eliminar/{id_mascota}")
    public ResponseEntity<Mascota> eliminarMasco(@PathVariable Mascota id_mascota){
        Mascota masco = mascotaService.encontrarMasco(id_mascota);
        if(masco != null){
            mascotaService.eliminar(masco);
        }else{
            return new ResponseEntity<Mascota>(masco, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(masco, HttpStatus.OK);
    }

    @GetMapping("/citas")
    public List<Cita> listarCitas(){
        return citaService.listarCitas();
    }

    @PostMapping("/cita/agregar")
    public ResponseEntity<Cita> agregarCita(@RequestBody Cita cita){
        Cita cita1 = citaService.guardarCita(cita);
        return new ResponseEntity<Cita>(cita1, HttpStatus.OK);
    }

    @GetMapping("/cita/{id_cita}")
    public Cita encontrarCita(@PathVariable Cita id_cita){
        return citaService.encontrarCita(id_cita);
    }

    @GetMapping("/cita/eliminar/{id_cita}")
    public ResponseEntity<Cita> eliminarCita(@PathVariable Cita id_cita){
        Cita cita1 = citaService.encontrarCita(id_cita);
        if(cita1 != null){
            citaService.eliminarCita(cita1);
        }else{
            return new ResponseEntity<Cita>(cita1, HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<Cita>(cita1, HttpStatus.OK);
    }
}
