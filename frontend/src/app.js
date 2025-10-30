import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/login';
import './styles/style.css';
import CrearUsuario from './components/CrearUsuario';
import RegistroAlumno from './components/RegistroAlumno';
import RegistroMaestro from './components/RegistroMaestro';
import DashboardMaestro from './components/DashboardMaestro';
import DashboardAlumno from './components/DashboardAlumno';
import NuevaAsesoria from './components/NuevaAsesoria';
import SolicitarAsesoria from './components/SolicitarAsesoria';
import VerAsesoria from './components/VerAsesoria';
import VerAsesoriaTotales from './components/VerAsesoriaTotales';
import EditarAsesoria from './components/EditarAsesoria';
import PagoAsesoria from './components/PagoAsesoria';
import VerDetalleAsesoria from './components/VerDetalleAsesoria';

// --- ✅ NUEVA IMPORTACIÓN ---
import ProtectedRoute from './components/ProtectedRoute'; // Importar el componente de protección

function App() {
  return (
    <Router>
      <Routes>
        {/* --- Rutas Públicas --- */}
        {/* Redirigir la raíz a /login */}
        <Route path="/" element={<Navigate to="/login" replace />} />
        
        {/* Rutas de autenticación y registro (públicas) */}
        <Route path="/login" element={<Login />} />
        <Route path="/crear_usuario" element={<CrearUsuario />} />
        <Route path="/registro_alumno" element={<RegistroAlumno />} />
        <Route path="/registro_maestro" element={<RegistroMaestro />} />

        
        {/* --- Rutas Protegidas para Alumnos --- */}
        <Route 
          path="/dashboard_alumno" 
          element={
            <ProtectedRoute roleRequired="alumno">
              <DashboardAlumno />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/ver_asesoria/:id" 
          element={
            <ProtectedRoute roleRequired="alumno">
              <VerAsesoria />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/pago_asesoria/:id" 
          element={
            <ProtectedRoute roleRequired="alumno">
              <PagoAsesoria />
            </ProtectedRoute>
          } 
        />
         <Route 
          path="/ver_asesorias_totales" 
          element={
            <ProtectedRoute roleRequired="alumno">
              <VerAsesoriaTotales />
            </ProtectedRoute>
          } 
        />
         <Route 
          path="/solicitar_asesoria" // Esta ruta no estaba, pero la protejo por si acaso
          element={
            <ProtectedRoute roleRequired="alumno">
              <SolicitarAsesoria />
            </ProtectedRoute>
          } 
        />
        
        {/* --- Rutas Protegidas para Maestros --- */}
        <Route 
          path="/dashboard_maestro" 
          element={
            <ProtectedRoute roleRequired="maestro">
              <DashboardMaestro />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/nueva_asesoria" 
          element={
            <ProtectedRoute roleRequired="maestro">
              <NuevaAsesoria />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/editar_asesoria/:id" 
          element={
            <ProtectedRoute roleRequired="maestro">
              <EditarAsesoria />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/ver_detalle_asesoria_maestro/:id" 
          element={
            <ProtectedRoute roleRequired="maestro">
              <VerDetalleAsesoria />
            </ProtectedRoute>
          } 
        />
        
        {/* Ruta duplicada de "VerDetalle" (la corrijo) */}
        {/* La ruta 'ver_detalle_asesoria' ahora es de ALUMNO */}
        <Route 
          path="/ver_detalle_asesoria/:id" 
          element={
            <ProtectedRoute roleRequired="alumno">
              <VerAsesoria />
            </ProtectedRoute>
          } 
        />

        {/* --- Ruta de Fallback --- */}
        {/* Si se escribe cualquier otra cosa, redirige a /login */}
        <Route path="*" element={<Navigate to="/login" replace />} />

      </Routes>
    </Router>
  );
}

export default App;
