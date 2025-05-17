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

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/crear_usuario" element={<CrearUsuario />} />
        <Route path="/registro_alumno" element={<RegistroAlumno />} />
        <Route path="/registro_maestro" element={<RegistroMaestro />} />
        <Route path="/dashboard_maestro" element={<DashboardMaestro />} />
        <Route path="/dashboard_alumno" element={<DashboardAlumno />} />
        <Route path="/nueva_asesoria" element={<NuevaAsesoria />} />
        <Route path="/solicitar_asesoria" element={<SolicitarAsesoria />} />
        <Route path="/ver_asesoria/:id" element={<VerAsesoria />} />
        <Route path="/ver_asesorias_totales" element={<VerAsesoriaTotales />} />
        <Route path="/ver_detalle_asesoria/:id" element={<VerDetalleAsesoria />} />
        <Route path="/ver_detalle_asesoria_maestro/:id" element={<VerDetalleAsesoria />} />
        <Route path="/editar_asesoria/:id" element={<EditarAsesoria />} />
        <Route path="/pago_asesoria/:id" element={<PagoAsesoria />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Router>
  );
}

export default App;