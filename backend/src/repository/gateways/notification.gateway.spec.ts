import { Test, TestingModule } from '@nestjs/testing';
import { NotificationGateway } from './notification.gateway';
import { Server, Socket } from 'socket.io';

describe('NotificationGateway', () => {
  let gateway: NotificationGateway;

  const mockServer = {
    emit: jest.fn(),
  };

  const mockSocket = {
    id: 'test-socket-id',
  } as unknown as Socket;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [NotificationGateway],
    }).compile();

    gateway = module.get<NotificationGateway>(NotificationGateway);
    gateway.server = mockServer as unknown as Server;

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(gateway).toBeDefined();
  });

  describe('handleConnection', () => {
    it('should log connection', () => {
      const loggerSpy = jest.spyOn((gateway as any).logger, 'log');
      gateway.handleConnection(mockSocket);
      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('test-socket-id'));
    });
  });

  describe('handleDisconnect', () => {
    it('should log disconnection', () => {
      const loggerSpy = jest.spyOn((gateway as any).logger, 'log');
      gateway.handleDisconnect(mockSocket);
      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('test-socket-id'));
    });
  });

  describe('sendScanUpdate', () => {
    it('should emit scanUpdated event', () => {
      gateway.sendScanUpdate(1, 'completed');
      expect(mockServer.emit).toHaveBeenCalledWith('scanUpdated', {
        scanId: 1,
        status: 'completed',
      });
    });
  });

  describe('afterInit', () => {
    it('should log initialization', () => {
      const loggerSpy = jest.spyOn((gateway as any).logger, 'log');
      gateway.afterInit(mockServer as any);
      expect(loggerSpy).toHaveBeenCalledWith(expect.stringContaining('Initialized'));
    });
  });
});
