import { Routes } from '@angular/router';
import { AppLayout } from './layout/component/app.layout';
import { AppDashboard } from './dashboard/dashboard';
import { AddRepoComponent } from './add-repo/add-repo';
import { SSHKeyManagementComponent } from './ssh-keys/ssh-keys';
import { ApiKeyManagementComponent } from './api-keys/api-keys';
import { ScanCenterComponent } from './scan-center/scan-center';
import { UsersComponent } from './users/users';
import { LoginComponent } from './auth/login.component';
import { DepotsComponent } from './depots/depots';
import { ContainersComponent } from './containers/containers';
import { AddContainerComponent } from './containers/add-container/add-container';
import { authGuard } from './auth/auth.guard';
import { adminGuard } from './auth/admin.guard';
import { AdminSettingsComponent } from './admin/admin-settings.component';

export const routes: Routes = [
    {
        path: '', component: AppLayout,
        canActivate: [authGuard],
        children: [
            { path: '', component: AppDashboard },
            { path: 'scan-center', component: ScanCenterComponent },
            { path: 'add-repo', component: AddRepoComponent },
            { path: 'ssh-keys', component: SSHKeyManagementComponent },
            { path: 'api-keys', component: ApiKeyManagementComponent },
            { path: 'users', component: UsersComponent },
            { path: 'depots', component: DepotsComponent },
            { path: 'containers', component: ContainersComponent },
            { path: 'add-container', component: AddContainerComponent },
            { path: 'admin/settings', component: AdminSettingsComponent, canActivate: [adminGuard] }
        ]
    },
    { path: 'login', component: LoginComponent },
    { path: '**', redirectTo: '' }
];
