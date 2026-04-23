import { Injectable } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class SocketService {
  private socket: Socket;
  private readonly url: string = 'http://localhost:3000';

  constructor() {
    this.socket = io(this.url);
  }

  onScanUpdated(): Observable<{ scanId: number, status: string }> {
    return new Observable(observer => {
      this.socket.on('scanUpdated', (data) => {
        observer.next(data);
      });
    });
  }

  onConnect(): Observable<void> {
    return new Observable(observer => {
      this.socket.on('connect', () => {
        observer.next();
      });
    });
  }

  onDisconnect(): Observable<void> {
    return new Observable(observer => {
      this.socket.on('disconnect', () => {
        observer.next();
      });
    });
  }
}
