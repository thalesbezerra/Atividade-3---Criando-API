using Exo.WebApi.Models;
using Exo.WebApi.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Exo.WebApi.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UsuarioRepository _usuarioRepository;

        public UsuariosController(UsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }

        // GET -> /api/usuarios
        [HttpGet]
        public IActionResult Listar()
        {
            return Ok(_usuarioRepository.Listar());
        }

        // POST -> /api/usuarios
        // Realiza o login e gera o token JWT.
        [HttpPost]
        public IActionResult Post(Usuario usuario)
        {
            Usuario usuarioBuscado =
                _usuarioRepository.Login(usuario.Email, usuario.Senha);

            if (usuarioBuscado == null)
            {
                return NotFound("E-mail ou senha inválidos!");
            }

            // Define os dados que serão fornecidos no token - Payload.
            var claims = new[]
            {
                // Armazena na claim o e-mail do usuário autenticado.
                new Claim(
                    JwtRegisteredClaimNames.Email,
                    usuarioBuscado.Email
                ),

                // Armazena na claim o ID do usuário autenticado.
                new Claim(
                    JwtRegisteredClaimNames.Jti,
                    usuarioBuscado.Id.ToString()
                )
            };

            // Define a chave de acesso ao token.
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("exoapi-chaveautenticacao")
            );

            // Define as credenciais do token.
            var creds = new SigningCredentials(
                key,
                SecurityAlgorithms.HmacSha256
            );

            // Gera o token.
            var token = new JwtSecurityToken(
                issuer: "exoapi.webapi",
                audience: "exoapi.webapi",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
            );

            // Retorna o token.
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token)
            });
        }

        // GET -> /api/usuarios/{id}
        // Faz a busca pelo ID.
        [HttpGet("{id}")]
        public IActionResult BuscarPorId(int id)
        {
            Usuario usuario = _usuarioRepository.BuscaPorId(id);

            if (usuario == null)
            {
                return NotFound();
            }

            return Ok(usuario);
        }

        // PUT -> /api/usuarios/{id}
        // Atualiza o usuário.
        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Atualizar(int id, Usuario usuario)
        {
            _usuarioRepository.Atualizar(id, usuario);

            return StatusCode(204);
        }

        // DELETE -> /api/usuarios/{id}
        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Deletar(int id)
        {
            try
            {
                _usuarioRepository.Deletar(id);

                return StatusCode(204);
            }
            catch (Exception)
            {
                return BadRequest();
            }
        }
    }
}